rule FlateDecode_wrong_version_ren: PDF {
  meta:
    author      = "Glenn Edwards (@hiddenillusion)"
    description = "Flate was introduced in v1.2"
    ref         = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
    version     = "0.1"
    weight      = 1

  strings:
    $magic = "%PDF"
    $js    = /\/FlateDecode/
    $ver   = /%PDF-1\.[2-9]/

  condition:
    $magic at 0 and $js and not $ver
}