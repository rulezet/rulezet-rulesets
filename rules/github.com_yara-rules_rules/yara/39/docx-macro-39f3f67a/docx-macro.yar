rule docx_macro : mail
{
  strings:
    $header="PK" 
    $vbaStrings="word/vbaProject.bin" nocase

  condition:
    $header at 0 and $vbaStrings
}