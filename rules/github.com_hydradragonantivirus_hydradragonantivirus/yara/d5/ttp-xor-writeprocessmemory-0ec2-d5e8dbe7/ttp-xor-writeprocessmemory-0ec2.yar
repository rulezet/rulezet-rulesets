rule TTP_XOR_WriteProcessMemory_0ec2 {
  strings:
    $key_0ec2 = { 59 b0 [2] 6b 92 [2] 6d a7 [2] 43 a7 [2] 7c bb }

  condition:
    any of them
}