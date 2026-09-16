rule TTP_XOR_WriteProcessMemory_fa9a {
  strings:
    $key_fa9a = { ad e8 [2] 9f ca [2] 99 ff [2] b7 ff [2] 88 e3 }

  condition:
    any of them
}