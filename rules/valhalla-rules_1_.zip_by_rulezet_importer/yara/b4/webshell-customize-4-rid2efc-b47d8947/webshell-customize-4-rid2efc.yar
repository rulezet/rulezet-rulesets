rule Webshell_Customize_4_RID2EFC : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file Customize.aspx"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:37:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ds.Clear();ds.Dispose();}else{SqlCommand cm = Conn.CreateCommand();cm.CommandTex" ascii
      $s2 = "c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=tr" ascii
      $s3 = "Stream WF=WB.GetResponseStream();FileStream FS=new FileStream(Z2,FileMode.Create" ascii
      $s4 = "R=\"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";}Conn.Close();break;" ascii
   condition: 
      filesize < 24KB and all of them
}