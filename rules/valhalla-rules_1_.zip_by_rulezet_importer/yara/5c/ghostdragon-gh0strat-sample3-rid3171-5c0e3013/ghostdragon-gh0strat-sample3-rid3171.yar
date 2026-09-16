rule GhostDragon_Gh0stRAT_Sample3_RID3171 : CHINA DEMO Gh0stRAT MAL {
   meta:
      description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
      author = "Florian Roth"
      reference = "https://blog.cylance.com/the-ghost-dragon"
      date = "2016-04-23 13:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1be9c68b31247357328596a388010c9cfffadcb6e9841fb22de8b0dc2d161c42"
      tags = "CHINA, DEMO, Gh0stRAT, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 44 24 15 65 88 54 24 16 c6 44 24 } 
      $op2 = { 44 24 1b 43 c6 44 24 1c 75 88 54 24 1e } 
      $op3 = { 1e 79 c6 44 24 1f 43 c6 44 24 20 75 88 54 24 22 } 
   condition: 
      all of them
}