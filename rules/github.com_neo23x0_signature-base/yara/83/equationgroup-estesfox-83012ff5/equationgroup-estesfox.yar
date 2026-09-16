rule EquationGroup_estesfox {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file estesfox"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "33530cae130ee9d9deeee60df9292c00242c0fe6f7b8eedef8ed09881b7e1d5a"
      id = "f2e8b8ba-af09-5e7c-a99c-4f620a0917c9"
   strings:
      $x1 = "chown root:root x;chmod 4777 x`' /tmp/logwatch.$2/cron" fullword ascii
   condition:
      all of them
}