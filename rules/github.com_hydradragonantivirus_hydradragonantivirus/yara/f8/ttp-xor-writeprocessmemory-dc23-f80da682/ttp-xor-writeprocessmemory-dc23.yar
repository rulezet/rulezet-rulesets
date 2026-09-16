rule TTP_XOR_WriteProcessMemory_dc23 {
  strings:
    $key_dc23 = { 8b 51 [2] b9 73 [2] bf 46 [2] 91 46 [2] ae 5a }

  condition:
    any of them
}