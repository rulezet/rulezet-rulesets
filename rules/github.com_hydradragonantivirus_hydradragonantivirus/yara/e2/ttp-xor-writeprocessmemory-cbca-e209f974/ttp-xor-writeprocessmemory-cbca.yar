rule TTP_XOR_WriteProcessMemory_cbca {
  strings:
    $key_cbca = { 9c b8 [2] ae 9a [2] a8 af [2] 86 af [2] b9 b3 }

  condition:
    any of them
}