rule Jupyter_Infostealer_PowerShell
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed powershell command strings"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $a = /\[.\..\]::run\(\)/ nocase
      $b = /\[.\..\]::run\(\)/ nocase wide
      $c = "[Reflection.Assembly]::Load("
      $d = /\[[a-zA-Z0-9\._]{25,45}\]::[a-zA-Z0-9\._]{10,25}\(\)/
  condition:
      ($a or $b) or ($c and $d)
}