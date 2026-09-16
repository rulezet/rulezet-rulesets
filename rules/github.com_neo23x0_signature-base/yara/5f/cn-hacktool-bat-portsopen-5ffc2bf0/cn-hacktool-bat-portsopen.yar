rule CN_Hacktool_BAT_PortsOpen {
   meta:
      description = "Detects a chinese BAT hacktool for local port evaluation"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "12.10.2014"
      id = "55c3f678-ba70-5a4a-b288-9d0953eff968"
   strings:
      $s0 = "for /f \"skip=4 tokens=2,5\" %%a in ('netstat -ano -p TCP') do (" ascii
      $s1 = "in ('tasklist /fi \"PID eq %%b\" /FO CSV') do " ascii
      $s2 = "@echo off" ascii
   condition:
      all of them
}