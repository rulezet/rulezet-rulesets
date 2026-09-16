rule TTP_XOR_WriteProcessMemory_fb63 {
  strings:
    $key_fb63 = { ac 11 [2] 9e 33 [2] 98 06 [2] b6 06 [2] 89 1a }

  condition:
    any of them
}