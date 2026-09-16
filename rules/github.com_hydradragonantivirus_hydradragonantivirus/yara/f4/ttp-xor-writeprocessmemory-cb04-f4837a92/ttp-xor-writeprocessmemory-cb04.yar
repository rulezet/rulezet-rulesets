rule TTP_XOR_WriteProcessMemory_cb04 {
  strings:
    $key_cb04 = { 9c 76 [2] ae 54 [2] a8 61 [2] 86 61 [2] b9 7d }

  condition:
    any of them
}