---
layout: post
title: Deep Learning Python
categories:
  - Notes
  - deeplearning
tags:
  - notes
---
# Pandas Usage
#pandas
### Generating Dataframe from CSV
```python
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt # For data visualization

df = pd.read_csv('bear.csv')
df.head()

```


### Processing
```python
print(df.info())
```
#### Distribution
```python
### Showing historgram 
import matplotlib.pyplot as plt
print(df['tune'])
df['tune'].plot(kind='hist', bins=1000, title='Distribution of `tune` Feature')
plt.xlabel('Tune Value')
plt.ylabel('Frequency')
plt.show()
### Bar bart showing the number of occrences
df['bear'].value_counts().plot(kind='barh', title='Frequency of Bear Types')
plt.xlabel('Number of Occrences')
plt.ylabel('Bear Type')
plt.show()
### List unique data
unique_values = df['val'].unique()
print("Unique characters in the 'val' column:", unique_values)


```
#### Mean
```python
# Group by the val type and aggregate to the average `tune` value
mean_tunes = df.groupby('val')['tune'].mean()
print(mean_tunes)
#Group by bear type to teh average 'tune'
mean_tunes = df.groupby('bear')['tune'].mean()
print(mean_tunes)

```

#### Filtering
Generating new DF from original DF with a filter
```python
# Filtering to find entries where 'tune' values are above a certain threshold
high_tune_bears = df[df['tune'] > 90]
print(high_tune_bears.head(5))

# Applying multiple conditions to find a specific subset of data
specific_bears = df[(df['tune'] > 50) & (df['bear'] == 'Kodiak')]
print(specific_bears.head(5))
```

