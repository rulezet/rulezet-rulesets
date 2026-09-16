rule FVEY_ShadowBroker_user_tool_pork {
   meta:
      description = "Auto-generated rule - file user.tool.pork.COMMON"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "9c400aab74e75be8770387d35ca219285e2cedc0c7895225bbe567ce9c9dc078"
      id = "ee5f88b1-6e58-5288-8b80-0d3d188e1ac6"
   strings:
      $x2 = "packrat -z RAT_REMOTE_NAME" fullword ascii
      $s3 = "./client -t TIME_ADJ SPECIAL_SOURCE_PORT 127.0.0.1 TARG_PORT" ascii
      $s4 = "mkdir TEMP_DIR; cd TEMP_DIR; cat < /dev/tcp/REDIR_IP/RED" ascii
   condition:
      1 of them
}