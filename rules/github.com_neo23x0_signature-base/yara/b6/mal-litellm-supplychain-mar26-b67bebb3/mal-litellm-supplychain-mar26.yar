rule MAL_LiteLLM_SupplyChain_Mar26 {
   meta:
      description = "Detects malicious indicators used in LiteLLM supply chain attack"
      author = "Marius Benthin"
      date = "2026-03-28"
      reference = "https://github.com/BerriAI/litellm/issues/24512"
      hash = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
      score = 80
      id = "a6ea2621-af92-591c-89e1-5be6efe9f6b8"
   strings:
      $s1 = "exec(base64.b64decode("
      $s2 = "litellm." base64
      $s3 = "subprocess.DEVNULL"
   condition:
      filesize < 500KB
      and all of them
}