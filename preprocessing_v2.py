import numpy as np
import pandas as pd
import re
import requests
import whois
import dns.resolver
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from bs4.element import Comment
from collections import Counter
from urllib.parse import urlparse
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from tld import get_tld
from pathlib import Path
import favicon
import multiprocessing as mp

key = 'cook8wokwwk888kw04c8kc8ks4g4s8s0kskcwow4'
HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']


def path_level(url):
    return len(Path(url).parents)

def url_length(url):
    return len(url)

def num_dash(url):
    return url.count('-')

def url_numeric(url):
    return sum(c.isdigit() for c in url)


def actual_word_rate(url):
    regex = r"\b[\w']+\b"
    words = re.findall(regex, url)
    if len(words) == 0:
        return 0
    word_checks = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(
            requests.get, f"https://api.datamuse.com/words?sp={word}") for word in words]
        for future in concurrent.futures.as_completed(futures):
            data = future.result().json()
            word_checks.append(len(data) > 0)

    count = sum(word_checks)
    return count / len(words)


def hostname_len(url):
    hostname = urlparse(url).netloc
    return len(hostname)



def url_path_length(url):
    path = urlparse(url).path
    return len(path)

def extract_text_from_url(url):
    def tag_visible(element):
        if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
            return False
        if isinstance(element, Comment):
            return False
        return True
    try:
        HEADERS = {
            'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'}
        html = requests.get(url, headers=HEADERS).text
        soup = BeautifulSoup(html, 'html.parser')
        texts = soup.findAll(text=True)
        visible_texts = filter(tag_visible, texts)
        return u" ".join(t.strip() for t in visible_texts)
    except requests.exceptions.RequestException:
        return ""


def find_k_most_frequent_words(url, k):
    full_text = extract_text_from_url(url)
    split_text = full_text.split()
    return sum([s in url for s in [item[0] for item in Counter(split_text).most_common(k)]])


def embedded_brand_name(url):
    return find_k_most_frequent_words(url, 20)

def get_links(url):
  try:
    soup = BeautifulSoup(requests.get(url).text, "html.parser")
    links = [list(filter(None,link["href"].split('/'))) for link in soup.find_all("a", href=lambda href: href and not href.startswith("#"))]
    return links
  except requests.exceptions.RequestException:
    return []

def get_links_for_mailto(url):
    links = []
    try:
        HEADERS = {
            'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'}
        html = requests.get(url, headers=HEADERS).text
        soup = BeautifulSoup(html, 'html.parser')
        # get all links from <a>
        a_tags = soup.findAll('a')
        for a_tag in a_tags:
            links.append(a_tag.get('href'))
        return links
    except requests.exceptions.RequestException:
        return []
    
def get_links_for_mail(url):
  links = []
  try:
    HEADERS = {'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'}
    html = requests.get(url, headers=HEADERS).text
    soup = BeautifulSoup(html, 'html.parser')
    # get all links from <a>
    a_tags = soup.findAll('a')
    for a_tag in a_tags:
      links.append(a_tag.get('href'))
    return links
  except requests.exceptions.RequestException:
    return []


def pct_ext_hyperlinks(url):
    links = get_links(url)
    if (links == []):
        return 1  # no links -> suspicious
    count = sum([(link is not None and link != [] and (
        'http' in link[0]) and ('.' in link[-1])) for link in links])
    return count/len(links)

def external_resources(url):
    links = get_links(url)
    if (links == []):
        return 1  # no links -> suspicious
    count = sum([(link is not None and link != [] and (
        'http' in link[0]) and ('.' not in link[-1])) for link in links])
    return count/len(links)


def ext_favicon(url):
    domain = str(get_tld(url, as_object=True).domain)
    try:
        fav_url = favicon.get(url)[0].url
        if domain not in fav_url:
            return True
        return False
    except:
        return True


def get_links_in_forms(url):
    link = []
    try:
        HEADERS = {
            'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'}
        html = requests.get(url, headers=HEADERS).text
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.findAll('form')
        for form in forms:
            form_elm = BeautifulSoup(str(form), 'html.parser')
            new_link = [a.get('href') for a in form_elm.findAll('a')]
            link += new_link
        return link
    except requests.exceptions.RequestException:
        return []


def insecure_form(url):
    if any("http" not in link for link in get_links_in_forms(url)):
        return True
    return False


def submit_info_to_email(url):
    if any(link and "mailto" in link for link in get_links_for_mailto(url)):
        return True
    return False

def frame_or_iframe(url):
    try:
        HEADERS = {
            'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'}
        html = requests.get(url, headers=HEADERS).text
        soup = BeautifulSoup(html, 'html.parser')
        iframes = soup.findAll('iframe')
        frames = soup.findAll('frame')
        if frames or iframes:
            return True
        return False
    except requests.exceptions.RequestException:
        return True

def url_prefix_suffix(url):
    try:
        hostname = urlparse(url).netloc
        if "-" in hostname:
            return True
        return False
    except:
        return True


def request_url(url):
    try:
        i = 0
        unsafe = 0
        soup = BeautifulSoup(requests.get(url).text, "html.parser")
        domain = str(get_tld(url, as_object=True).domain)
        for img in soup.find_all('img', src=True):
            if domain not in img['src']:
                unsafe = unsafe + 1
            i = i + 1

        for iframe in soup.find_all('iframe', src=True):
            if domain not in iframe['src']:
                unsafe = unsafe + 1
            i = i + 1

        # sound
        for sound in soup.find_all('embed', src=True):
            if domain not in sound['src']:
                unsafe = unsafe + 1
            i = i + 1

        # video
        for video in soup.find_all('video', src=True):
            if domain not in video['src']:
                unsafe = unsafe + 1
            i = i + 1

        if i == 0:
            return 0
        # if unsafe/float(i) > 0.5:
        #     return 1
        return unsafe/float(i)
    except:
        return 1

# url_of_anchor:


def url_of_anchor(url):
    try:
        soup = BeautifulSoup(requests.get(url).text, "html.parser")
        domain = str(get_tld(url, as_object=True).domain)
        i = 0
        unsafe = 0
        for a in soup.find_all('a', href=True):
            i += 1
            if a['href'].startswith('#') or a['href'].startswith('javascript:') or a['href'].startswith('#skip') or a['href'].startswith('#content'):
                unsafe += 1
            elif domain not in a['href']:
                unsafe += 1
        if i == 0:
            return 0
        # if unsafe/float(i) > 0.9:
        #     return 1
        return unsafe/float(i)
    except:
        return 1

# links_in_tags:


def links_in_tags(url):
    try:
        soup = BeautifulSoup(requests.get(url).text, "html.parser")
        domain = str(get_tld(url, as_object=True).domain)

        i = 0
        unsafe = 0
        for link in soup.find_all('link', href=True):
            i += 1
            if domain not in link['href']:
                unsafe += 1
        if i == 0:
            return 0
        # if unsafe/float(i) > 0.9:
        #     return 1
        return unsafe/float(i)
    except:
        return 1

# sfh: >0.5


def sfh(url):
    try:
        soup = BeautifulSoup(requests.get(url).text, "html.parser")
        domain = str(get_tld(url, as_object=True).domain)
        i = 0
        unsafe = 0
        for form in soup.find_all('form', action=True):
            i += 1
            if domain not in form['action']:
                unsafe += 1
            elif form['action'] == "about:blank" or form['action'] == "":
                unsafe += 1
        if i == 0:
            return 0
        # if unsafe/float(i) > 0.5:
        #     return 1
        return unsafe/float(i)
    except:
        return 1

# abnormal_url: True => phishing


def abnormal_url(url):
    try:
        w = whois.whois(url)
        if w.status == None:
            return True
        else:
            return False
    except:
        return True

# domain_age < 500 => phishing, 500 < domain_age < 4000 => suspicious


def domain_age(url):
    try:
        w = whois.whois(url)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        age = (datetime.now() - creation_date).days
        return age
        # if age < 500:
        #     return 1
        # elif age > 4000:
        #     return 0
        # else:
        #     return -1
    except:
        return -1

# check_dns_record: false => phishing

def check_dns_record(hostname):
    try:
        answers = dns.resolver.query(hostname, 'A')
        if answers:
            return True
        else:
            return False
    except:
        return False
    
def page_rank(key, url):
    domain = urlparse(url).netloc
    urlApi = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(urlApi, headers={'API-OPR':key})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return -1


def google_index(url):
    google = "https://www.google.com/search?q=site:" + url + "&hl=en"
    response = requests.get(google, cookies={"CONSENT": "YES+1"})
    soup = BeautifulSoup(response.content, "html.parser")
    not_indexed = re.compile("did not match any documents")

    if soup(text=not_indexed):
        return False
    return True

def check_www(url):
    words_raw = re.findall(r"\b[\w']+\b", url)
    count = 0
    for word in words_raw:
        if not word.find('www') == -1:
            count += 1
    return count

    
def phish_hints(url):
    url_path = urlparse(url).path
    count = 0
    for hint in HINTS:
        count += url_path.lower().count(hint)
    return count

def extract(url):
    # return [path_level(url), url_length(url), num_dash(url), url_numeric(url), actual_word_rate(url), hostname_len(url), url_path_length(url), embedded_brand_name(url), pct_ext_hyperlinks(url), external_resources(url), ext_favicon(url), insecure_form(url), submit_info_to_email(url), frame_or_iframe(url), url_prefix_suffix(url), request_url(url), url_of_anchor(url), links_in_tags(url), sfh(url), abnormal_url(url), domain_age(url), check_dns_record(url)]
    # parallel
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future1 = executor.submit(path_level, url)
        future2 = executor.submit(url_length, url)
        future3 = executor.submit(num_dash, url)
        future4 = executor.submit(url_numeric, url)
        future5 = executor.submit(actual_word_rate, url)
        future6 = executor.submit(hostname_len, url)
        future7 = executor.submit(url_path_length, url)
        future8 = executor.submit(embedded_brand_name, url)
        future9 = executor.submit(pct_ext_hyperlinks, url)
        future10 = executor.submit(external_resources, url)
        future11 = executor.submit(ext_favicon, url)
        future12 = executor.submit(insecure_form, url)
        future13 = executor.submit(submit_info_to_email, url)
        future14 = executor.submit(frame_or_iframe, url)
        future15 = executor.submit(url_prefix_suffix, url)
        future16 = executor.submit(request_url, url)
        future17 = executor.submit(url_of_anchor, url)
        future18 = executor.submit(links_in_tags, url)
        future19 = executor.submit(sfh, url)
        future20 = executor.submit(abnormal_url, url)
        future21 = executor.submit(domain_age, url)
        future22 = executor.submit(check_dns_record, url)
        future23 = executor.submit(page_rank, url)
        future24 = executor.submit(google_index, url)
        future25 = executor.submit(check_www, url)
        future26 = executor.submit(phish_hints, url)


        return [future1.result(), future2.result(), future3.result(), future4.result(), future5.result(), future6.result(), future7.result(), future8.result(), future9.result(), future10.result(), future11.result(), future12.result(), future13.result(), future14.result(), future15.result(), future16.result(), future17.result(), future18.result(), future19.result(), future20.result(), future21.result(), future22.result(), future23.result(), future24.result(), future25.result(), future26.result()]

# def normalize(list_feature):
#     list_feature[0] = 1 if list_feature[0] <= 2 or list_feature[0] > 10 else 0
#     list_feature[1] = 1 if list_feature[1] >= 35 and list_feature[1] <= 40 else 0
#     list_feature[2] = 1 if list_feature[2] == 1 else 0
#     list_feature[3] = -1 if list_feature[3] >= 1 and list_feature[3] <= 20 else 1 if list_feature[3] > 20 else 0
#     list_feature[4] = 1 if list_feature[4] < 0.8 else 0 if list_feature[4] > 0.9 else -1
#     list_feature[5] = 1 if list_feature[5] > 25 else 0
#     list_feature[6] = 1 if list_feature[6] <= 10 else 0
#     list_feature[7] = 1 if list_feature[7] < 1 else 0
#     list_feature[8] = 1 if list_feature[8] > 0.5 else 0
#     list_feature[9] = 1 if list_feature[9] > 0.5 else 0
#     list_feature[10] = 1 if list_feature[10] == True else 0
#     list_feature[11] = 1 if list_feature[11] == True else 0
#     list_feature[12] = 1 if list_feature[12] == True else 0
#     list_feature[13] = 1 if list_feature[13] == True else 0
#     list_feature[14] = 1 if list_feature[14] == True else 0
#     list_feature[15] = 1 if list_feature[15] > 0.5 else 0
#     list_feature[16] = 1 if list_feature[16] > 0.9 else 0
#     list_feature[17] = 1 if list_feature[17] > 0.9 else 0
#     list_feature[18] = 1 if list_feature[18] > 0.5 else 0
#     list_feature[19] = 1 if list_feature[19] == True else 0
#     list_feature[20] = 1 if list_feature[20] < 500 else -1 if list_feature[20] < 4000 else 0
#     list_feature[21] = 1 if list_feature[21] == False else 0

#     return list_feature

def detect_phishing(url):
    list_feature = extract(url)
    return list_feature
