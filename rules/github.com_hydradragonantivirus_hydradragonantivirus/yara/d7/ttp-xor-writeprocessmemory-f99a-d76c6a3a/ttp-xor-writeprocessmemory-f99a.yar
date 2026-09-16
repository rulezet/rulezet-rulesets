rule TTP_XOR_WriteProcessMemory_f99a {
  strings:
    $key_f99a = { ae e8 [2] 9c ca [2] 9a ff [2] b4 ff [2] 8b e3 }

  condition:
    any of them
}