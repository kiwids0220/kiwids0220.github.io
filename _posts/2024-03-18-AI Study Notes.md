---
layout: post
title: Dive into Deep Learning Study Notes
categories: [Notes, deeplearning] 
tags:
  - notes
---
# Introduction
### Four Main Categories

- Analyze pass data, predict future outcome - **speech recognition**
- Read the questions in text and answer them based on knowledge trained - **NLP**
- Identify animals from an given image - **computer vision**
- Promote potential goods to the customer's based on pass purchasing experience or searches - **recommendation engines**

### Machine Learning Concept
#concept

Even when we don't know hot to program a hardware to explicitly do certain actions : a application uses microphone to collect inputs and analyze the voice messages. We, the human brains are nonetheless capable of performing the cognitive feat ourselves


### How 
#parameters #参数
A way to solve problem using "machine learning" is to define a flexible program whose ==behavior== is determined by a number of ==parameters==.

==parameters== are set by ==analyzing dataset==  to determine the best possible ==parameter==values.

### Parameter, Model, Learning Alogorithm

>You can think of the parameters as knobs that we can turn, manipulating the behavior of the program. Once the parameters are fixed, we call the program a ==_model_==. The set of all distinct programs (input–output mappings) that we can produce just by manipulating the parameters is called a ==_family_ of models==. And the “meta-program” that uses our dataset to choose the parameters is called a ==_learning algorithm_==.

### The Learning
 the _learning_ is the process by which we discover the right setting of the knobs for coercing the desired behavior from our model. In other words, we _train_ our model with data. As shown in [Fig. 1.1.2](https://d2l.ai/chapter_introduction/index.html#fig-ml-loop), the training process usually looks like the following:

1. Start off with a randomly initialized model that cannot do anything useful.
2. Grab some of your data (e.g., audio snippets and corresponding {yes,no} labels).
3. Tweak the knobs to make the model perform better as assessed on those examples.
4. Repeat Steps 2 and 3 until the model is awesome.
 ![](/assets/images/1.%20Introduction-2024-03-17.png)

### Supervised Learning

- Input 
- Input label
- predict a designated unknown label based on known inputs given a dataset.
#questions
- How should the data be prepared?
- Where to gather all the data?
- How to create the algorithm?

### Always
#questions
- Data we can learn from
- Model of how to transform the data
- Objectivefunction that quantified how well the model is doing
- Algorithm to adjust the model's parameters 


### What is Data (brief)
- with ==features== that a model can make its prediction on its ==label== (not part of the model's input - feature)

#### Fixed-length vector examples

when a example inputs have the same number of numerical features 

### Variable-length example
- Text
- images with different sizes
#### How do we determine/harvest features out of a input?

### Training Set vs Testing Set
#objectivefunction
- Objective function - formal measures of how good the model is
- Training Set - A dataset has minimized input error, which will lead to minimized loss function /objective function
- Test Set - held out for evaluation

### Models

These models consist of many successive transformations of the data that are chained together top to bottom, thus the name _deep learning_. On our way to discussing deep models, we will also discuss some more traditional methods.
#statisticalmodels
- statistical models can be estimated from data.

### Objective Functions
#objectivefunction 
a mathmatical function to value the how well a model is at its job.

### Optimization Algo
an algo that search for the best possble ==parameters for minimizing the loss function/objective function==. 
Usually based on an popular approach called ==gradient descent==


### Kinds of Machine Learning Problems

- [Supervised Learning](https://d2l.ai/chapter_introduction/index.html#supervised-learning) : Feature - label pair, we are the supervisors who provide the model with a dataset consisting of labeled examples.
	- **Regression** : When labels (e.g., house selling price) are taken on ***arbitrary numerical values***, and we will work on minimizing the squared error
		- How many hours will this surgery take?
		- How much rainfall this town have in the next 6 hours
	- **Classification** : Identify **one*** category an example belongs, grouping examples into different categories. Seed for a **classifier***. 
		- Binary Classification
		- Multiclass Classification
		- Hierarchically structures classes
			- level of classes and sub-classes (dogs, different breeds of dogs)
	- **Tagging** : Instead of classifying, predict classes that are not **mutally exclusive*** is called **multilabel classification***
	- **Search** : scoring relevant pages and display them with priorities. 
	- **Recommendation Systems** : Different than ^ is the emphasis on **personalization*** to specific users.
	- **Sequence Learning** : Unlike previous model where the **test example are forgotten after model processing**. This is not ideal for **Processing Videos***  == Each example (frame) might be drastically different; For more time sensitive problems.
		- Tagging  and Parsing : A sequence of ***aligned text***, tagging the word if they are referring entities or direct objects.
		- Automaic Speed Recognition: audio recording
		- Machine Translation: input and output may appear if different order 
- **Unsupervised** and **Self-Supervised** Learning
	- **Clusetering**, can we group something together given the 
	- **Subspace Estimation**
	- causality, probabilistic graphical models 
- **Offline Learning** vs **Environment aware**
	- remember env
	- determine the env 
	- shifting dynamics
- **Reinforcement Learning**
	- interacts with env and **Take Actions*** which actually impacts the environment. (e.g., AlphaGo)
	- Solved the problem where the **agent receives observation*** from the environment and must chooser **an corrsponding action***
	- Goal of the learning is to **provide a good mapping from observation of the environment to actions***
![](/assets/images/03-20-20242024-03-18-AI%20Study%20Notes-2.png)
![](/assets/images/03-20-20242024-03-18-AI%20Study%20Notes-3.png)


# Preliminaries

## Ndarray

#tensor
- `Tensor` in PyTorch and TensorFlow
- `ndarray` in MXNet
- NumPy's `ndarray`
 First, the tensor class supports automatic differentiation. Second, it leverages GPUs to accelerate numerical computation, whereas NumPy only runs on CPUs.

### Tensor Operations
```python
x = torch.arange(12, dtype=torch.float32)
x.numel()
12
## Access Shape of the tenso
x.shape

## Reshape the vector into a matrice
x_reshaped=x.reshape(3,4)
tensor([[ 0.,  1.,  2.,  3.],
        [ 4.,  5.,  6.,  7.],
        [ 8.,  9., 10., 11.]])
torch.zeros((2,3,4))

torch.tensor([[2, 1, 4, 3], [1, 2, 3, 4], [4, 3, 2, 1]])

```

```python
x = torch.tensor([1.0, 2, 4, 8])
y = torch.tensor([2, 2, 2, 2])
x + y, x - y, x * y, x / y, x ** y
```