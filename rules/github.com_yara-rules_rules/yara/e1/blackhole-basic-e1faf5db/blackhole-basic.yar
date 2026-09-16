rule blackhole_basic :  EK
{
    strings:
        $a = /\.php\?.*?\:[a-zA-Z0-9\:]{6,}?\&.*?\&/
    condition:
        $a
}