rule png_file
{
  strings :
    $magic = { 89 50 4E 47 0D 0A 1A 0A }
  condition:
    $magic at 0
}