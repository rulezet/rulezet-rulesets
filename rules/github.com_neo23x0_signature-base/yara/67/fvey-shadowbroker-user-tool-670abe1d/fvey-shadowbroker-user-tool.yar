rule FVEY_ShadowBroker_user_tool {
   meta:
      description = "Auto-generated rule - file user.tool.elatedmonkey"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "98ae935dd9515529a34478cb82644828d94a2d273816d50485665535454e37cd"
      id = "b1ca04e5-bac7-5247-b2d4-82c3515c92fc"
   strings:
      $x5 = "ELATEDMONKEY will only work of apache executes scripts" fullword ascii
   condition:
      1 of them
}