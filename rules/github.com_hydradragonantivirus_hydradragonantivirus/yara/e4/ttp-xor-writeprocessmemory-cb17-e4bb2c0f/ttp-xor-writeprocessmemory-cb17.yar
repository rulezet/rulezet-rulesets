rule TTP_XOR_WriteProcessMemory_cb17 {
  strings:
    $key_cb17 = { 9c 65 [2] ae 47 [2] a8 72 [2] 86 72 [2] b9 6e }

  condition:
    any of them
}