
rule Suspicious_URLs
{
    meta:
        description = "Detects suspicious URLs in files"
        author = "Fixion"
        category = "network"

    strings:
        $url1 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $url2 = ".tk/" nocase
        $url3 = ".ml/" nocase
        $url4 = ".ga/" nocase
        $url5 = ".bit/" nocase
        $url6 = ".onion/" nocase

    condition:
        any of them
}

rule IRC_Bot_Indicators
{
    meta:
        description = "Detects IRC bot indicators"
        author = "Fixion"
        category = "botnet"

    strings:
        $irc1 = "PRIVMSG"
        $irc2 = "JOIN #"
        $irc3 = "NICK "
        $irc4 = "USER "
        $irc5 = "MODE "

    condition:
        3 of ($irc*)
}
