rule MAL_LiteLLM_SupplyChain_Mar26_RID3173 : DEMO MAL {
   meta:
      description = "Detects malicious indicators used in LiteLLM supply chain attack"
      author = "Marius Benthin"
      reference = "https://github.com/BerriAI/litellm/issues/24512"
      date = "2026-03-28 13:23:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL"
      minimum_yara = "4.0.0"
      
   strings:
      $s1 = "exec(base64.b64decode(" 
      $s2 = "litellm." base64
      $s3 = "subprocess.DEVNULL" 
   condition: 
      filesize < 500KB and all of them
}