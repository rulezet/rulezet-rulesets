rule TTP_XOR_WriteProcessMemory_2888 {
  strings:
    $key_2888 = { 7f fa [2] 4d d8 [2] 4b ed [2] 65 ed [2] 5a f1 }

  condition:
    any of them
}