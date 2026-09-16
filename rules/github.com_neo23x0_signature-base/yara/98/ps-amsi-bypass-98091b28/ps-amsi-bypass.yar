rule PS_AMSI_Bypass : FILE {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://gist.github.com/mattifestation/46d6a2ebb4a1f4f0e7229503dc012ef1"
      date = "2017-07-19"
      score = 65
      id = "31ab8932-4c74-5251-a044-3fcc0aa159f4"
   strings:
      $s1 = ".GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')." ascii nocase
   condition:
      1 of them
}