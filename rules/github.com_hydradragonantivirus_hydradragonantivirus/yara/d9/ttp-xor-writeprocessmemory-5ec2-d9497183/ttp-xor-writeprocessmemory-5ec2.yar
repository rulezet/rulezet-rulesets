rule TTP_XOR_WriteProcessMemory_5ec2 {
  strings:
    $key_5ec2 = { 09 b0 [2] 3b 92 [2] 3d a7 [2] 13 a7 [2] 2c bb }

  condition:
    any of them
}