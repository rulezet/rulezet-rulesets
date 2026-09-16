rule Webshell_aspbackdoor_asp1_RID3103 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file asp1.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 13:04:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "param = \"driver={Microsoft Access Driver (*.mdb)}\" " fullword ascii
      $s1 = "conn.Open param & \";dbq=\" & Server.MapPath(\"scjh.mdb\") " fullword ascii
      $s6 = "set rs=conn.execute (sql)%> " fullword ascii
      $s7 = "<%set Conn = Server.CreateObject(\"ADODB.Connection\") " fullword ascii
      $s10 = "<%dim ktdh,scph,scts,jhqtsj,yhxdsj,yxj,rwbh " fullword ascii
      $s15 = "sql=\"select * from scjh\" " fullword ascii
   condition: 
      all of them
}