rule TTP_XOR_WriteProcessMemory_5bcf {
  strings:
    $key_5bcf = { 0c bd [2] 3e 9f [2] 38 aa [2] 16 aa [2] 29 b6 }

  condition:
    any of them
}