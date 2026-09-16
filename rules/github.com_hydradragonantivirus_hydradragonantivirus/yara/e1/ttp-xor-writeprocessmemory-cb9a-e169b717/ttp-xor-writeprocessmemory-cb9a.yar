rule TTP_XOR_WriteProcessMemory_cb9a {
  strings:
    $key_cb9a = { 9c e8 [2] ae ca [2] a8 ff [2] 86 ff [2] b9 e3 }

  condition:
    any of them
}