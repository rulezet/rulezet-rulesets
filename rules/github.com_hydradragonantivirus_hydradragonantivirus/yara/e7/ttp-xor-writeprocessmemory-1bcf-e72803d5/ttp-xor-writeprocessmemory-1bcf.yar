rule TTP_XOR_WriteProcessMemory_1bcf {
  strings:
    $key_1bcf = { 4c bd [2] 7e 9f [2] 78 aa [2] 56 aa [2] 69 b6 }

  condition:
    any of them
}