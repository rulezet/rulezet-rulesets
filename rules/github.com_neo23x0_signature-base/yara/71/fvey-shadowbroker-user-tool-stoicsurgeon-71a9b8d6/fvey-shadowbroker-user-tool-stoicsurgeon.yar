rule FVEY_ShadowBroker_user_tool_stoicsurgeon {
   meta:
      description = "Auto-generated rule - file user.tool.stoicsurgeon.COMMON"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "967facb19c9b563eb90d3df6aa89fd7dcfa889b0ba601d3423d9b71b44191f50"
      id = "2ff22b17-4922-54d7-bbd8-a5ff40b6ebe5"
   strings:
      $x1 = "echo -n TARGET_HOSTNAME  | sed '/\\n/!G;s/\\(.\\)\\(.*\\n\\)/&\\2\\1/;//D;s/.//'" fullword ascii
   condition:
      1 of them
}