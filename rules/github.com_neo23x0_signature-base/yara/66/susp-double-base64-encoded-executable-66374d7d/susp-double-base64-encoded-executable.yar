rule SUSP_Double_Base64_Encoded_Executable {
   meta:
      description = "Detects an executable that has been encoded with base64 twice"
      author = "Florian Roth"
      reference = "https://twitter.com/TweeterCyber/status/1189073238803877889"
      score = 70
      date = "2019-10-29"
      modified = "2025-03-21"
      hash = "ef2fc4e10cadb9a1e890208e8ec634d09bb505cce87a3c91a80e5c796bfafb43"
      hash = "f40c6116c05fbd0433fe4031a896e882c5d31059b93b5015a019c04e2a1add32"
      hash = "e396d1e1957e12595250ff85a7613873a065177c6e5b665e0f2b9f14224e33a3"
      hash = "ea96c8696d48884f337e19dfa4220c13200a28192220ebb1a856a7fd850dff99"
   strings:
   
      $ = "VkdocGN5QndjbTluY21GdElHTmhibTV2ZENCaVpTQnlkVzRnYVc0Z1JFOVRJRzF2Wk" ascii wide
      $ = "ZHaHBjeUJ3Y205bmNtRnRJR05oYm01dmRDQmlaU0J5ZFc0Z2FXNGdSRTlUSUcxdlpH" ascii wide
      $ = "WR2hwY3lCd2NtOW5jbUZ0SUdOaGJtNXZkQ0JpWlNCeWRXNGdhVzRnUkU5VElHMXZaR" ascii wide
      $ = "Um9hWE1nY0hKdlozSmhiU0JqWVc1dWIzUWdZbVVnY25WdUlHbHVJRVJQVXlCdGIyUm" ascii wide
      $ = "JvYVhNZ2NISnZaM0poYlNCallXNXViM1FnWW1VZ2NuVnVJR2x1SUVSUFV5QnRiMlJs" ascii wide
      $ = "Sb2FYTWdjSEp2WjNKaGJTQmpZVzV1YjNRZ1ltVWdjblZ1SUdsdUlFUlBVeUJ0YjJSb" ascii wide
      $ = "VWFHbHpJSEJ5YjJkeVlXMGdZMkZ1Ym05MElHSmxJSEoxYmlCcGJpQkVUMU1nYlc5a1" ascii wide
      $ = "VhR2x6SUhCeWIyZHlZVzBnWTJGdWJtOTBJR0psSUhKMWJpQnBiaUJFVDFNZ2JXOWta" ascii wide
      $ = "VYUdseklIQnliMmR5WVcwZ1kyRnVibTkwSUdKbElISjFiaUJwYmlCRVQxTWdiVzlrW" ascii wide
      $ = "VkdocGN5QndjbTluY21GdElHMTFjM1FnWW1VZ2NuVnVJSFZ1WkdWeUlGZHBiak15" ascii wide
      $ = "ZHaHBjeUJ3Y205bmNtRnRJRzExYzNRZ1ltVWdjblZ1SUhWdVpHVnlJRmRwYmpNe" ascii wide
      $ = "WR2hwY3lCd2NtOW5jbUZ0SUcxMWMzUWdZbVVnY25WdUlIVnVaR1Z5SUZkcGJqTX" ascii wide
      $ = "Um9hWE1nY0hKdlozSmhiU0J0ZFhOMElHSmxJSEoxYmlCMWJtUmxjaUJYYVc0ek" ascii wide
      $ = "JvYVhNZ2NISnZaM0poYlNCdGRYTjBJR0psSUhKMWJpQjFibVJsY2lCWGFXNHpN" ascii wide
      $ = "Sb2FYTWdjSEp2WjNKaGJTQnRkWE4wSUdKbElISjFiaUIxYm1SbGNpQlhhVzR6T" ascii wide
      $ = "VWFHbHpJSEJ5YjJkeVlXMGdiWFZ6ZENCaVpTQnlkVzRnZFc1a1pYSWdWMmx1TX" ascii wide
      $ = "VhR2x6SUhCeWIyZHlZVzBnYlhWemRDQmlaU0J5ZFc0Z2RXNWtaWElnVjJsdU16" ascii wide
      $ = "VYUdseklIQnliMmR5WVcwZ2JYVnpkQ0JpWlNCeWRXNGdkVzVrWlhJZ1YybHVNe" ascii wide
   condition:
      1 of them
      and not filepath contains "\\User Data\\Default\\Cache\\"       and not filepath contains "\\cache2\\entries\\"       and not filepath contains "\\Microsoft\\Windows\\INetCache\\IE\\" }