import pandas as pd 
import URL_Component_Extraction as u


class Data:
    def __init__(self,path) :
        self.temp = pd.read_csv(path) # load data
        self.data = self.temp.copy()
    def add_feature(self):
        for index, row in self.data.iterrows():
        # Perform component extraction on each element of the row
            url = row['url']
            self.data.at[index , "having_ip_address"] = u.having_IP(url)
            self.data.at[index , "have_dns"] = u.check_dns_record(url)
            self.data.at[index , "subdomains"] = u.check_subdomains(url)
            self.data.at[index , "valid_tld"] = u.check_tld(url)
            self.data.at[index , "http"] = u.check_http(url)
            self.data.at[index , "file_extension"] = u.check_malicious_file_extension(url)
            self.data.at[index , "shorten_URL"] = u.check_shorten_URL(url)
            self.data.at[index , "redirection"] = u.check_redirection(url)
            self.data.at[index , "prefix_suffix"] = u.prefix_suffix(url)
            self.data.at[index , "length"] = u.check_length(url)
            self.data.at[index , "symbols"] = u.check_symbols(url)
            self.data.at[index , "have_https"] = u.check_https(url)
            #self.data.at[index , "iframe"] = u.check_iframe(url)
       
            
            
            
            
    #     data['having_ip_address'] = self.data['url'].apply(lambda i:self.having_IP(i))
    #     data['have_dns'] = self.data['url'].apply(lambda i: self.check_dns_record(i))
    #     self.data['have_https'] = self.data['url'].apply(lambda i: self.check_https(i))
    #     self.data['subdomains'] = self.data['url'].apply(lambda i: self.check_subdomains(i))
    #     self.data['valid_tld'] = self.data['url'].apply(lambda i: self.check_tld(i))
    #     self.data['http'] = self.data['url'].apply(lambda i: self.check_http(i))
    #     self.data['exe&zip'] = self.data['url'].apply(lambda i: self.check_exe_or_zip(i))
    #     self.data['length'] = self.data['url'].apply(lambda i: self.check_length(i))
    #     self.data['shorten_URL'] = self.data['url'].apply(lambda i: self.check_shorten_URL(i))
    #     self.data['redirection'] = self.data['url'].apply(lambda i: self.check_redirection(i))
    #     self.data['prefix_suffix'] = self.data['url'].apply(lambda i: self.prefix_suffix(i))
    #     self.data['have_@'] = self.data['url'].apply(lambda i: self.haveAtSign(i))
        
        # Perform any additional operations on value1 and value2 as needed
        
       
             
        
        
    def get_data(self):
        return self.data
        
        
temp = Data("final.csv")
temp.add_feature()
temp.data.to_csv("temp.csv")
#print(temp.data)