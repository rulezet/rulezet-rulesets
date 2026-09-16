rule TTP_XOR_WriteProcessMemory_cbfb {
  strings:
    $key_cbfb = { 9c 89 [2] ae ab [2] a8 9e [2] 86 9e [2] b9 82 }

  condition:
    any of them
}