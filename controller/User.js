const { User } = require('../model/User');

exports.fetchUserById = async (req, res) => {
  // FIX: If the route is /own, use req.user.id (from Token). 
  // Otherwise use req.params.id (from URL)
  const { id } = req.params;
  const userId = (id === 'own') ? req.user.id : id;

  console.log("Fetching user for ID:", userId); // Debug log

  try {
    // We usually want to project fields (remove password/salt)
    const user = await User.findById(userId, 'name email id role addresses orders'); 
    
    if (!user) {
       return res.status(400).json({message: "User not found"});
    }
    res.status(200).json(user);
  } catch (err) {
    res.status(400).json(err);
  }
};

// ... keep updateUser as is ...
exports.updateUser = async (req, res) => {
  const { id } = req.params;
  try {
    const user = await User.findByIdAndUpdate(id, req.body, { new: true });
    res.status(200).json(user);
  } catch (err) {
    res.status(400).json(err);
  }
};