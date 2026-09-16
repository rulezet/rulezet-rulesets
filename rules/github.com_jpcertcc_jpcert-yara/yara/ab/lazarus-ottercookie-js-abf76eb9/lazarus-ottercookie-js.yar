rule Lazarus_OtterCookie_js {
   meta:
      description = "OtterCookie downloader js"
      author = "JPCERT/CC Incident Response Group"
      created_date = "2025-04-02"
      updated_date = "2025-04-02"
      hash = "71d2fd0c71b44331e08f11a254e7acc2cec3067dbd8f4848d5ef11e5a59ea253"

   strings:
      $str1 = "const GET_RPCNODE_URL = `${domain}/${subdomain}/${id}`;" ascii
      $str2 = "axios.get(GET_RPCNODE_URL)" ascii
      $str3 = "catch(err=>eval(err.response.data));" ascii

   condition:
      all of them
}