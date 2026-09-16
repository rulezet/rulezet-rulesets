rule TTP_XOR_WriteProcessMemory_c075 {
  strings:
    $key_c075 = { 97 07 [2] a5 25 [2] a3 10 [2] 8d 10 [2] b2 0c }

  condition:
    any of them
}