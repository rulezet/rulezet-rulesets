rule Hacktools_CN_Panda_Burst {
   meta:
      description = "Disclosed hacktool set - file Burst.rar"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "ce8e3d95f89fb887d284015ff2953dbdb1f16776"
      id = "e07c66d1-958e-5ad2-9d5b-380d48af8360"
   strings:
      $s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http://60.15.124.106:63389/tasksvr." ascii
   condition:
      all of them
}