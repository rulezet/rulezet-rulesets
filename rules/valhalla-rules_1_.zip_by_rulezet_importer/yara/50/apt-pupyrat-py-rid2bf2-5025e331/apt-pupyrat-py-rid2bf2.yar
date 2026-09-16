rule APT_PupyRAT_PY_RID2BF2 : APT DEMO EXE FILE SCRIPT {
   meta:
      description = "Detects Pupy RAT"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
      date = "2017-02-17 09:28:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8d89f53b0a6558d6bb9cdbc9f218ef699f3c87dd06bc03dd042290dedc18cb71"
      tags = "APT, DEMO, EXE, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "reflective_inject_dll" fullword ascii
      $x2 = "ImportError: pupy builtin module not found !" fullword ascii
      $x3 = "please start pupy from either it's exe stub or it's reflective DLLR;" fullword ascii
      $x4 = "[INJECT] inject_dll." fullword ascii
      $x5 = "import base64,zlib;exec zlib.decompress(base64.b64decode('eJzzcQz1c/ZwDbJVT87Py0tNLlHnAgA56wXS'))" fullword ascii
      $op1 = { 8b 42 0c 8b 78 14 89 5c 24 18 89 7c 24 14 3b fd } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20000KB and 1 of them ) or ( 2 of them )
}