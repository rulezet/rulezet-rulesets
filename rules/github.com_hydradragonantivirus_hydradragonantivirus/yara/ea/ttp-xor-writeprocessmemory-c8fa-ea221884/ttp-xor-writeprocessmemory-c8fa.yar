rule TTP_XOR_WriteProcessMemory_c8fa {
  strings:
    $key_c8fa = { 9f 88 [2] ad aa [2] ab 9f [2] 85 9f [2] ba 83 }

  condition:
    any of them
}