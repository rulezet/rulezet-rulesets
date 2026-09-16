rule TTP_XOR_WriteProcessMemory_e8fa {
  strings:
    $key_e8fa = { bf 88 [2] 8d aa [2] 8b 9f [2] a5 9f [2] 9a 83 }

  condition:
    any of them
}