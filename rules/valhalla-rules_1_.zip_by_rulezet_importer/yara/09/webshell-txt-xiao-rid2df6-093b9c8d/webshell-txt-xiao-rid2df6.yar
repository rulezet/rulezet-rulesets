rule Webshell_Txt_xiao_RID2DF6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file xiao.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:54:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
      $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
      $s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
      $s4 = "function Command(cmd, str){" fullword ascii
      $s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii
   condition: 
      filesize < 100KB and all of them
}