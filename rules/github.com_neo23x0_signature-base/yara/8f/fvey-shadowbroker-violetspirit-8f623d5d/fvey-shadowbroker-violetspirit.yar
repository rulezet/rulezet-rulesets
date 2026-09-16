rule FVEY_ShadowBroker_violetspirit {
   meta:
      description = "Auto-generated rule - file violetspirit.README"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"
      id = "4efea734-8cbc-53f7-bf92-5b3253721a81"
   strings:
      $x1 = "-i tgt_ipaddr -h tgt_hostname" fullword ascii
   condition:
      1 of them
}