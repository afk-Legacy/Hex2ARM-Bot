import re

from convertor import b64_convert
re_pat = r"(?<=\[# \*\*)(.*?)(?=\*\* #\])"
url_pat = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"


def get_Author(ctx):
    if ctx.author.nick:
        return [ctx.author.nick, ctx.author.avatar_url]
    else:
        return [ctx.author.name,ctx.author.avatar_url]

def findURL(message):
    msg = message.content
    urls = re.findall(url_pat, msg)
    hasURL  = False
    if urls:
        hasURL = True
        for url in urls:
            match = url[0]
            msg = msg.replace(match, "[# **"+b64_convert(match, False)+"** #]")
    
    return msg, hasURL

def translateURL(string):
    result = ""

    urls = re.findall(re_pat, string)
    for url in urls:
        url = b64_convert(url, True)
        result += str(url + "\n")

    return result
         