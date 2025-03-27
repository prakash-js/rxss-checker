import argparse
import requests
import re
from colorama import init,Fore

init(autoreset=True)

args = argparse.ArgumentParser()

args.add_argument("--url", type=str, help="Specify a single URL.")
args.add_argument("--urlist", type=str, help="Use this when you have a URL wordlist.")
args.add_argument("--output", type=str, help="to save the output.")

args = args.parse_args()

payload = ["<R-Checker<tag>>", "%3CR-Checker%3Ctag%3E%3E", r"\<R-Checker\<tag\>\>",'&#60;R-Checker&#60;tag&#62;&#62;']

def url_list():
    with open(args.urlist , 'r') as wordlist:
        for urls in wordlist:
            XSS_check(urls)

def write_output(pass_url):
    if args.output:
        with open(args.output, 'a') as savelist:
            savelist.write(pass_url)
    else:
        pass


def single_url():
    XSS_check(args.url)

print("If Vulnerable URL found it will Display")


def reflection_validator(target_url):
    for payloads in payload:
        try:
            urls = target_url
            url = urls.replace("PAYLOAD", payloads)
            response = requests.get(url)
            if response.status_code == 200:
                output = response.text

                if re.search(r'(href|src|action)="([^"]*)' + re.escape(payloads) + r'[^"]*"', output, re.IGNORECASE):
                    continue

                if "<R-Checker<tag>>" in output:
                    print(f"{url}  \n  {Fore.YELLOW} Vulnerable Endpoint Found Reflects[<, >]")
                    write_output(url)
                    break

                if r"\<R-Checker\<tag\>\>" in output:
                    print(f"{url}" + "\n" + Fore.YELLOW + r"Vulnerable Endpoint Found Reflects[\<, >/]")
                    write_output(url)
                    break

            if response.status_code == 500:
                print(Fore.Red + f"{url} => {Fore.RED} 500 Internal Error")
                write_output(url)


        except requests.exceptions.RequestException as e:
            pass

def XSS_check(url):
    if "?" not in url:
        return 0
    split_url = url.split("?")
    key, value = split_url
    if "&" in value:
        new_value = value.split('&')
        modified_second = []
        for new_values in new_value:
            key2,value2 = new_values.split("=")
            modified_second.append(f"{key2}=PAYLOAD")
        joining = "&".join(modified_second)
        final_url = (key + "?" + joining)
        reflection_validator(final_url)


    else:
        primary_mod = []
        key3 , value3 = split_url
        again = value3.split("=")
        key4, value4 = again
        primary_mod.append(f"{key4}=PAYLOAD")
        final2_url = (key + "?" +"=".join(primary_mod))
        reflection_validator(final2_url)


if __name__ == "__main__":
    if args.url:
        single_url()

    if args.urlist:
        url_list()
