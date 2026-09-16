rule TTP_XOR_WriteProcessMemory_0bcf {
  strings:
    $key_0bcf = { 5c bd [2] 6e 9f [2] 68 aa [2] 46 aa [2] 79 b6 }

  condition:
    any of them
}