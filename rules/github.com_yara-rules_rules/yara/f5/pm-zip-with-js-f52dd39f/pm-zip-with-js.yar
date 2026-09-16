rule PM_Zip_with_js
{
  strings:
    $hdr="PK" 
    $e1=".js" nocase
    $e2=".jse" nocase

  condition:
    $hdr at 0 and (($e1 in (filesize-100..filesize)) or ($e2 in (filesize-100..filesize)))
}