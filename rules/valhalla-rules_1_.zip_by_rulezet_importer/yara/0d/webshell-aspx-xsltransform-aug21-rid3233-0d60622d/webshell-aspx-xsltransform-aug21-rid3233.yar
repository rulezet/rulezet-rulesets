rule WEBSHELL_ASPX_XslTransform_Aug21_RID3233 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects an ASPX webshell utilizing XSL Transformations"
      author = "Max Altgelt"
      reference = "https://gist.github.com/JohnHammond/cdae03ca5bc2a14a735ad0334dcb93d6"
      date = "2020-02-23 13:55:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $csharpshell = "Language=\"C#\"" nocase
      $x1 = "<root>1</root>" 
      $x2 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(" 
      $s1 = "XsltSettings.TrustedXslt" 
      $s2 = "Xml.XmlUrlResolver" 
      $s3 = "FromBase64String(Request[\"" 
   condition: 
      filesize < 500KB and $csharpshell and ( 1 of ( $x* ) or all of ( $s* ) )
}