---
layout: post
title: Useful Code Snippets
date: 2024-03-06
categories: [Notes, code]
tags:
  - notes
---

# C/C++

[Rule Of Three](https://en.cppreference.com/w/cpp/language/rule_of_three)
```cpp

template<typename Function>
inline auto LazyLoad(HMODULE library, const std::string& procName) {
    return (library) ? reinterpret_cast<Function*>(GetProcAddress(library, procName.data())) : nullptr;
}
#define LAZY_LOAD_PROC(LIBRARY, PROC) \
    auto lazy_##PROC{ LazyLoad<decltype(PROC)>(LIBRARY, #PROC) };

```


```cpp
class IObject
{
public:
	virtual ~IObject() {}
	virtual int CompareWith(const IObject &) const { throw std::runtime_error("Abstract method"); }
};

template <typename Object>
class ObjectList : public IObject
{
	//not implemented
	ObjectList &operator=(const ObjectList &);
public:
	explicit ObjectList() : IObject() {}
	explicit ObjectList(const ObjectList &src) : IObject(src) {}
	virtual ~ObjectList() { clear(); }
	virtual void clear()
	{
		while (!v_.empty()) {
			delete v_.back();
		}
	}
	void Delete(size_t index)
	{
		if (index >= v_.size())
			throw std::runtime_error("subscript out of range");
		delete v_[index]; 
	}
	size_t count() const { return v_.size(); }
	Object *item(size_t index) const
	{ 
		if (index >= v_.size())
			throw std::runtime_error("subscript out of range");
		return v_[index]; 
	}
	void resize(size_t size) {
		v_.resize(size);
	}
	Object *last() const { return v_.empty() ? NULL : *v_.rbegin(); }
	static bool CompareObjects(const Object *obj1, const Object *obj2) { return obj1->CompareWith(*obj2) < 0; }
	void Sort() { std::sort(v_.begin(), v_.end(), CompareObjects); }
	typedef typename std::vector<Object*>::const_iterator const_iterator;
	typedef typename std::vector<Object*>::iterator iterator;
	size_t IndexOf(const Object *obj) const
	{
		const_iterator it = std::find(v_.begin(), v_.end(), obj);
		return (it == v_.end()) ? -1 : it - v_.begin();
	}

	size_t IndexOf(const Object *obj, size_t index) const
	{
		const_iterator it = std::find((v_.begin()+index), v_.end(), obj);
		return (it == v_.end()) ? -1 : it - v_.begin();
	}
	void SwapObjects(size_t i, size_t j) { std::swap(v_[i], v_[j]); }
	virtual void AddObject(Object *obj) { v_.push_back(obj); }
	virtual void InsertObject(size_t index, Object *obj) { v_.insert(v_.begin() + index, obj); }
	virtual void RemoveObject(Object *obj)
	{ 
		for (size_t i = count(); i > 0; i--) {
			if (item(i - 1) == obj) {
				erase(i - 1);
				break;
			}
		}
	}
	void erase(size_t index) { v_.erase(v_.begin() + index); }
	void assign(const std::list<Object*> &src) 
	{ 
		v_.clear(); 
		for (typename std::list<Object*>::const_iterator it = src.begin(); it != src.end(); it++) {
			v_.push_back(*it);
		}
	}

	const_iterator begin() const { return v_.begin(); }
	const_iterator end() const { return v_.end(); }

	iterator _begin() { return v_.begin(); }
	iterator _end() { return v_.end(); }

protected:
	void Reserve(size_t count) { v_.reserve(count); }
	std::vector<Object*> v_;
};
```

# Python


```python
def enableHTTPdebug():
    try:
        import http.client as http_client
    except ImportError:
    # Python 2
        import httplib as http_client
        http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True
```