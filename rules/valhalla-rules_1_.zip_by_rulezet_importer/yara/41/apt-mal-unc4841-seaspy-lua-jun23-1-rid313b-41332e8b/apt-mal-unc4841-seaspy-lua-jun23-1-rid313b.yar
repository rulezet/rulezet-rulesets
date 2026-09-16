rule APT_MAL_UNC4841_SEASPY_LUA_Jun23_1_RID313B : APT DEMO MAL SCRIPT {
   meta:
      description = "Detects SEASPY malware related LUA script"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/"
      date = "2023-06-16 13:13:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "56e8066bf83ff6fe0cec92aede90f6722260e0a3f169fc163ed88589bffd7451"
      tags = "APT, DEMO, MAL, SCRIPT"
      minimum_yara = "4.0.0"
      
   strings:
      $x1 = "os.execute('rverify'..' /tmp/'..attachment:filename())" ascii fullword
      $x2 = "log.debug(\"--- opening archive [%s], mimetype [%s]\", tmpfile" ascii fullword
      $xe1 = "os.execute('rverify'..' /tmp/'..attachment:filename())" ascii base64
      $xe2 = "log.debug(\"--- opening archive [%s], mimetype [%s]\", tmpfile" ascii base64
   condition: 
      filesize < 500KB and 1 of them
}