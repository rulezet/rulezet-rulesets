rule rar_with_js
{
  strings:
  $h1 = "Rar!" 
  $s1 = ".js" nocase
    
  condition:
    $h1 at 0 and $s1
}