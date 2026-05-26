import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  try {
    const { initData, botToken } = await req.json()
    
    if (!initData || !botToken) {
      throw new Error('Missing initData or botToken')
    }

    // Парсим данные Telegram
    const params = new URLSearchParams(initData)
    const hash = params.get('hash')
    params.delete('hash')
    
    // Сортируем параметры (требование Telegram API)
    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join('\n')
    
    // Вычисляем секретный ключ
    const encoder = new TextEncoder()
    const keyData = encoder.encode(botToken)
    const keyBuffer = await crypto.subtle.digest('SHA-256', keyData)
    
    // Создаем HMAC подпись
    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyBuffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    )
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(dataCheckString))
    
    // Превращаем подпись в строку
    const computedHash = Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')

    // Сравниваем хеши
    if (computedHash !== hash) {
      return new Response(JSON.stringify({ error: 'Invalid Telegram signature' }), { 
        status: 401, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      })
    }

    // Всё ок! Достаем данные пользователя
    const userJSON = params.get('user')
    if (!userJSON) throw new Error('No user data in initData')
    
    const userData = JSON.parse(decodeURIComponent(userJSON))
    const telegramId = userData.id
    const username = userData.username || 'User_' + telegramId

    // Подключаемся к БД
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )

    // Проверяем/создаем пользователя
    const { data: existing, error: fetchError } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('telegram_id', telegramId)
      .single()

    if (fetchError && fetchError.code !== 'PGRST116') {
      throw fetchError
    }

    if (!existing) {
      const { error: insertError } = await supabaseAdmin
        .from('users')
        .insert({
          telegram_id: telegramId,
          username: username,
          wins: 0,
          losses: 0
        })
      if (insertError) throw insertError
    }

    return new Response(
      JSON.stringify({ success: true, user_id: telegramId, username: username }), 
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )

  } catch (error) {
    console.error('Error in verify-telegram:', error)
    return new Response(JSON.stringify({ error: error.message }), { 
      status: 500, 
      headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
    })
  }
})