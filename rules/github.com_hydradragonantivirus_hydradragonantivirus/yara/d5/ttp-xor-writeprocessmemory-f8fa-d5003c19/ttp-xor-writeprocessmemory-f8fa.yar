rule TTP_XOR_WriteProcessMemory_f8fa {
  strings:
    $key_f8fa = { af 88 [2] 9d aa [2] 9b 9f [2] b5 9f [2] 8a 83 }

  condition:
    any of them
}