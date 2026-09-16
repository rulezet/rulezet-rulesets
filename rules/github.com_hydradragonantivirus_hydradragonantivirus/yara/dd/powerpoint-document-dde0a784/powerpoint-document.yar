rule powerpoint_document
{
  strings:
    $pptdoc = "PowerPoint Document" wide nocase
    $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  condition:
    all of them
}