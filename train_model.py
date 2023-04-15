import pandas as pd 
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
 
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score
import URL_Component_Extraction  as c 
import Data
    

data = Data.Data("good.csv").get_data()
data = data.sample(frac=1).reset_index(drop=True) # shuffling the rows in the dataset
data = data.drop(data.columns[[0]],axis=1)

urls_without_labels = data.drop('label',axis=1)
labels = data['label']
# empty_rows = data.isnull().any(axis=1)
# # Print the empty rows
# print(empty_rows)
data_train, data_test, labels_train, labels_test = train_test_split(urls_without_labels, labels, test_size=0.20, random_state=100)
random_forest_classifier = RandomForestClassifier()
random_forest_classifier.fit(data_train,labels_train)


# DecisionTreeClassifier().fit(data_train,labels_train)
#data_test = Data.Data("test_data.csv").get_data()

prediction_label = random_forest_classifier.predict(data_test)

acc = accuracy_score(prediction_label, labels_test)

print(acc)

# import pickle
# filename = 'random_forest_classifier.pkl'
# pickle.dump(random_forest_classifier, open(filename, 'wb'))




    






